import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

import click

from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.config.auth_config import read_config_tokens
from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    KeyringTokenStore,
    humanize_keyring_error,
    keyring_fix_commands,
)
from ggshield.core.config.utils import get_auth_config_filepath
from ggshield.utils.os import getenv_bool


class TokenStorage(str, Enum):
    """Where an instance token actually lives, as diagnosed by `auth status`."""

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


@click.command()
@click.pass_context
@json_option
@text_json_format_option
@add_common_options()
def auth_status_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Show where API tokens are stored and whether the OS credential store works.

    Reports the credential-store backend, whether it is reachable, and where
    each instance's token actually lives (credential store vs cleartext config
    file). Useful when a token unexpectedly lands in plaintext, for example
    after ggshield was updated or reinstalled and its path changed (Homebrew,
    mise, asdf, pyenv, pipx).

    Note: on macOS this reads tokens from the Keychain, which may trigger an
    access-confirmation prompt the first time.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    disabled = getenv_bool("GGSHIELD_NO_KEYRING", default=False)
    store = KeyringTokenStore()
    # The user opted out of the credential store, so we do not probe it at all
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

    if ctx_obj.use_json:
        click.echo(
            json.dumps(
                {
                    "credential_store": {
                        "backend": store.backend_name,
                        "disabled": disabled,
                        "reachable": reachable,
                    },
                    "instances": [report.to_json() for report in reports],
                }
            )
        )
        return 0

    lines = [f"backend: {store.backend_name}"]
    if disabled:
        lines.append(
            "disabled: GGSHIELD_NO_KEYRING is set (tokens stored in config file)"
        )
    else:
        lines.append(f"reachable: {'yes' if reachable else 'no'}")

    if not reports:
        lines += ["", "No authenticated instances."]

    for report in reports:
        lines += ["", f"[{report.instance}]", f"token_storage: {report.status.value}"]
        if report.status is TokenStorage.OK:
            lines.append(f"location: {store.backend_name}")
        elif report.message:
            label = "error" if report.status is TokenStorage.FAILED else "reason"
            lines.append(f"{label}: {report.message}")
        if report.fix:
            lines += ["fix:"] + [f"  {command}" for command in report.fix]

    click.echo("\n".join(lines))
    return 0
