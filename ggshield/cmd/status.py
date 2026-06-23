#!/usr/bin/python3
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

import click
from pygitguardian.models import APITokensResponse, HealthCheckResponse

from ggshield.cmd.utils.common_options import (
    add_common_options,
    instance_option,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.config.auth_config import read_config_tokens
from ggshield.core.config.config import ConfigSource
from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    KeyringTokenStore,
    humanize_keyring_error,
    keyring_fix_commands,
)
from ggshield.core.config.utils import get_auth_config_filepath
from ggshield.core.errors import ExitCode, UnexpectedError
from ggshield.core.text_utils import STYLE, format_text
from ggshield.utils.os import getenv_bool


# --- API reachability report (network-dependent, degrades instead of aborting) ---


@dataclass
class _ApiReport:
    """Result of the API reachability/validity check.

    ``ok`` is True when the instance answered and the token is usable. On
    failure (no usable token, unreachable instance, …) the check degrades
    rather than aborting: ``ok`` is False, ``error`` holds the reason, and
    ``exit_code`` preserves the code the command would have exited with before
    (e.g. ``AUTHENTICATION_ERROR`` for a missing token).
    """

    ok: bool
    exit_code: int
    instance: Optional[str] = None
    instance_source: Optional[ConfigSource] = None
    api_key_source: Optional[ConfigSource] = None
    health: Optional[HealthCheckResponse] = None
    token_scopes: Optional[List[str]] = None
    workspace_id: Optional[int] = None
    error: Optional[str] = None


def _gather_api_report(config: Config) -> _ApiReport:
    """Probe the configured instance. Never raises: a failure is reported as a
    non-ok report so the storage diagnostic can still be shown."""
    try:
        client = create_client_from_config(config)
        response = client.health_check()
        if not isinstance(response, HealthCheckResponse):
            raise UnexpectedError("Unexpected health check response")

        token_scopes: Optional[List[str]] = None
        workspace_id: Optional[int] = None
        token_response = client.api_tokens()
        if isinstance(token_response, APITokensResponse):
            token_scopes = token_response.scopes
            workspace_id = token_response.workspace_id

        instance, instance_source = config.get_instance_name_and_source()
        _, api_key_source = config.get_api_key_and_source()
        return _ApiReport(
            ok=True,
            exit_code=ExitCode.SUCCESS,
            instance=instance,
            instance_source=instance_source,
            api_key_source=api_key_source,
            health=response,
            token_scopes=token_scopes,
            workspace_id=workspace_id,
        )
    except Exception as exc:
        # Preserve the exit code the command used to abort with, so scripts that
        # check `api-status`' exit status keep working.
        exit_code = int(getattr(exc, "exit_code", 0) or ExitCode.UNEXPECTED_ERROR)
        instance: Optional[str] = None
        instance_source: Optional[ConfigSource] = None
        try:
            instance, instance_source = config.get_instance_name_and_source()
        except Exception:
            pass
        error = (
            exc.format_message()
            if isinstance(exc, click.ClickException)
            else (str(exc) or exc.__class__.__name__)
        )
        return _ApiReport(
            ok=False,
            exit_code=exit_code,
            instance=instance,
            instance_source=instance_source,
            error=error,
        )


# --- Token storage report (local, read-only, never needs the network) ---


class TokenStorage(str, Enum):
    """Where an instance token actually lives, as diagnosed by the command."""

    OK = "ok"  # in the credential store and readable
    FAILED = "failed"  # marked for the credential store but unreadable
    PLAINTEXT = "plaintext"  # in cleartext in the config file (silent fallback)
    DISABLED = "disabled"  # credential store disabled via GGSHIELD_NO_KEYRING
    SKIPPED = "skipped"  # no token stored


@dataclass
class InstanceReport:
    instance: str
    status: TokenStorage
    # Human-readable explanation; None when the status alone says it all (OK)
    message: Optional[str] = None
    # Shell commands fixing the problem; None when there is nothing to fix
    fix: Optional[List[str]] = None

    def to_json(self) -> Dict[str, Any]:
        # Every status emits the same key set so consumers can rely on the
        # shape; message and fix are null when not applicable.
        return {
            "instance": self.instance,
            "status": self.status.value,
            "message": self.message,
            "fix": self.fix,
        }


@dataclass
class StorageReport:
    backend: str
    disabled: bool
    reachable: Optional[bool]
    instances: List[InstanceReport]

    def to_json(self) -> Dict[str, Any]:
        return {
            "credential_store": {
                "backend": self.backend,
                "disabled": self.disabled,
                "reachable": self.reachable,
            },
            "instances": [report.to_json() for report in self.instances],
        }


def _diagnose_instance(
    store: KeyringTokenStore,
    url: str,
    stored_token: Optional[str],
    *,
    disabled: bool,
    reachable: Optional[bool],
) -> InstanceReport:
    """Diagnose where the token for ``url`` is stored.

    The check is read-centric: what matters for day-to-day use is that the
    token is in the credential store and can be read back. A failed *write*
    (e.g. macOS -25244 when overwriting an entry owned by another binary path)
    only matters on the next save and is surfaced there, so it is not treated
    as a failure here.

    This is read-only: it never writes to the credential store, so running it
    cannot change where a token is stored.

    ``stored_token`` is the token as written on disk (the keyring sentinel, a
    cleartext token, or ``None``). ``reachable`` is whether the credential
    store answered the read probe (``None`` when disabled, in which case it
    was not probed); it only affects how a cleartext token is explained.
    """
    if not stored_token:
        return InstanceReport(url, TokenStorage.SKIPPED, message="no token stored")

    if disabled:
        # The user opted out of the credential store, so we do not probe it
        # (that could prompt for the very access they disabled). Report the
        # on-disk state and what it means.
        if stored_token == KEYRING_SENTINEL:
            message = (
                "token lives in the credential store but GGSHIELD_NO_KEYRING is "
                "set, so ggshield ignores it. Unset the variable or run "
                "`ggshield auth login` to use a token again."
            )
        else:
            message = (
                "token is stored in cleartext in the config file "
                "(credential store disabled via GGSHIELD_NO_KEYRING)."
            )
        return InstanceReport(url, TokenStorage.DISABLED, message=message)

    if stored_token == KEYRING_SENTINEL:
        # Token lives in the credential store. Verify we can read it back,
        # which is exactly what every command does at runtime.
        try:
            value = store.get_token(url)
        except Exception as exc:
            value = None
            read_error: Optional[str] = str(exc)
        else:
            read_error = None
        if value:
            return InstanceReport(url, TokenStorage.OK)
        return InstanceReport(
            url,
            TokenStorage.FAILED,
            message=(
                humanize_keyring_error(read_error)
                if read_error
                else "token is marked as stored in the credential store but could "
                "not be read back"
            ),
            fix=keyring_fix_commands(url),
        )

    # Token is in cleartext in the config file. We do not probe with a write
    # here (that would migrate the token as a side effect); the exact cause is
    # shown, humanized, the next time a save is attempted. Only claim a failed
    # attempt when the store answers probes: an unreachable store also leaves
    # tokens in cleartext, and that is expected rather than a failure.
    if reachable:
        message = (
            f"stored in cleartext in the config file, not in the "
            f"{store.backend_name}. A previous attempt to store it there failed."
        )
    else:
        message = (
            f"stored in cleartext in the config file; the {store.backend_name} "
            "is not reachable, so it cannot hold the token."
        )
    return InstanceReport(
        url,
        TokenStorage.PLAINTEXT,
        message=message,
        fix=keyring_fix_commands(url),
    )


def gather_storage_report(config: Config) -> StorageReport:
    """Diagnose where each instance token is stored. Local and read-only: it
    never hits the network and never needs a usable token, so it works even
    when the API check fails."""
    disabled = getenv_bool("GGSHIELD_NO_KEYRING", default=False)
    store = KeyringTokenStore()
    # The user opted out of the credential store, so we do not probe it at all.
    reachable: Optional[bool] = None if disabled else store.is_reachable()

    stored_tokens = read_config_tokens(get_auth_config_filepath())
    reports = [
        _diagnose_instance(
            store,
            instance.url,
            stored_tokens.get(instance.url),
            disabled=disabled,
            reachable=reachable,
        )
        for instance in config.auth_config.instances
    ]
    return StorageReport(
        backend=store.backend_name,
        disabled=disabled,
        reachable=reachable,
        instances=reports,
    )


# --- Rendering ---


def _api_json(api: _ApiReport) -> Dict[str, Any]:
    if api.ok:
        assert api.health is not None
        assert api.instance_source is not None
        assert api.api_key_source is not None
        output = api.health.to_dict()
        output["instance"] = api.instance
        output["instance_source"] = api.instance_source.name
        output["api_key_source"] = api.api_key_source.name
        if api.token_scopes is not None:
            output["token_scopes"] = api.token_scopes
        if api.workspace_id is not None:
            output["workspace_id"] = api.workspace_id
        return output

    output: Dict[str, Any] = {}
    if api.instance is not None:
        output["instance"] = api.instance
    if api.instance_source is not None:
        output["instance_source"] = api.instance_source.name
    if api.error is not None:
        output["detail"] = api.error
    return output


def _api_text(api: _ApiReport) -> List[str]:
    if not api.ok:
        lines = []
        if api.instance:
            lines.append(f"{format_text('API URL:', STYLE['key'])} {api.instance}")
        lines.append(
            f"{format_text('Status:', STYLE['key'])} "
            f"{format_text('unreachable', {'fg': 'red'})}"
        )
        if api.error:
            lines.append(f"{format_text('Detail:', STYLE['key'])} {api.error}")
        return lines

    assert api.health is not None
    assert api.instance_source is not None
    assert api.api_key_source is not None
    lines = [f"{format_text('API URL:', STYLE['key'])} {api.instance}"]
    if api.workspace_id is not None:
        lines.append(f"{format_text('Workspace ID:', STYLE['key'])} {api.workspace_id}")
    lines += [
        f"{format_text('Status:', STYLE['key'])} {format_healthcheck_status(api.health)}",
        f"{format_text('App version:', STYLE['key'])} {api.health.app_version or 'Unknown'}",
        f"{format_text('Secrets engine version:', STYLE['key'])} "
        f"{api.health.secrets_engine_version or 'Unknown'}",
        "",
        f"{format_text('Instance source:', STYLE['key'])} {api.instance_source.value}",
        f"{format_text('API key source:', STYLE['key'])} {api.api_key_source.value}",
    ]
    if api.token_scopes is not None:
        lines.append(
            f"{format_text('Token scopes:', STYLE['key'])} {', '.join(api.token_scopes)}"
        )
    return lines


def _storage_text(report: StorageReport) -> List[str]:
    lines = [f"{format_text('Credential store:', STYLE['key'])} {report.backend}"]
    if report.disabled:
        lines.append(
            f"{format_text('Storage:', STYLE['key'])} disabled "
            "(GGSHIELD_NO_KEYRING is set, tokens stored in config file)"
        )
    else:
        lines.append(
            f"{format_text('Reachable:', STYLE['key'])} "
            f"{'yes' if report.reachable else 'no'}"
        )

    if not report.instances:
        lines += ["", "No authenticated instances."]

    for report_ in report.instances:
        lines += [
            "",
            f"[{report_.instance}]",
            f"{format_text('Token storage:', STYLE['key'])} {report_.status.value}",
        ]
        if report_.status is TokenStorage.OK:
            lines.append(f"{format_text('Location:', STYLE['key'])} {report.backend}")
        elif report_.message:
            label = "Error" if report_.status is TokenStorage.FAILED else "Reason"
            lines.append(f"{format_text(label + ':', STYLE['key'])} {report_.message}")
        if report_.fix:
            lines.append(f"{format_text('Fix:', STYLE['key'])}")
            lines += [f"  {command}" for command in report_.fix]
    return lines


@click.command()
@text_json_format_option
@json_option
@instance_option
@add_common_options()
@click.pass_context
def status_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """Show API status and version, and where API tokens are stored.

    Reports two things:

    - API: whether the configured GitGuardian instance is reachable and the
      token valid, with the instance/key sources (the original `api-status`
      output). If the instance is unreachable or no usable token is found, this
      degrades to an error line instead of aborting.

    - Token storage: which credential-store backend is in use, whether it is
      reachable, and where each instance token actually lives (credential store
      vs cleartext config file), with a fix when a token unexpectedly stays in
      plaintext. This part is local and read-only, so it works even when the
      API check fails.

    `ggshield auth status` is an alias of this command.

    Note: on macOS reading tokens from the Keychain may trigger an
    access-confirmation prompt the first time.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    api = _gather_api_report(config)
    storage = gather_storage_report(config)

    if ctx_obj.use_json:
        output = _api_json(api)
        output["token_storage"] = storage.to_json()
        click.echo(json.dumps(output))
    else:
        lines = _api_text(api) + [""] + _storage_text(storage)
        click.echo("\n".join(lines))

    # Exit code is driven solely by the API check (as before); a token storage
    # problem is informational and never changes it.
    return int(api.exit_code)


def format_healthcheck_status(health_check: HealthCheckResponse) -> str:
    (color, status) = (
        ("red", f"unhealthy ({health_check.detail})")
        if health_check.status_code != 200
        else ("green", "healthy")
    )

    return format_text(status, {"fg": color})
