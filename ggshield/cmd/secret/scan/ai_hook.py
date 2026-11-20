import contextlib
import sys
from dataclasses import replace
from typing import Any, ContextManager

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config.token_store import (
    ALLOW_KEYCHAIN_DIALOG_ENV_VAR,
    keychain_prompts_disabled,
)
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.os import getenv_bool
from ggshield.verticals.ai.hooks import (
    AIHookScanner,
    UnrecognizedAgentError,
    build_agent_headers,
    emit_cannot_scan_response,
    resolve_ai_hook_failure_policy,
)
from ggshield.verticals.secret import SecretScanner


MAX_READ_SIZE = 1024 * 1024 * 10  # We restrict stdin read to 10MB


def _fail(ctx_obj: ContextObj) -> bool:
    policy = ctx_obj.config.user_config.secret.ai_hook_failure_policy
    return resolve_ai_hook_failure_policy(policy) == "block"


def _keychain_dialogs() -> ContextManager[None]:
    """Allow a Keychain dialog only when a user can see it.

    Agents run the hook in the background, so Keychain reads fail instead of
    showing a dialog. Only the `machine setup` warm-up, which runs while the
    user is at the terminal, sets the variable that allows the dialog.
    """
    if getenv_bool(ALLOW_KEYCHAIN_DIALOG_ENV_VAR):
        return contextlib.nullcontext()
    return keychain_prompts_disabled()


# Kept visible in help (a user debugging the hook should be able to read it),
# but the help text makes clear it is invoked automatically by the installed
# hooks and is not meant to be run manually. The command string is persisted in
# each assistant's settings, so it must stay stable and never break.
@click.command()
@add_secret_scan_common_options()
@click.pass_context
def ai_hook_cmd(
    ctx: click.Context,
    **kwargs: Any,
) -> int:
    """
    Scan AI tool interactions for secrets.

    This command is invoked automatically by the ggshield AI hooks installed in
    your coding assistant; it is not meant to be run manually. It reads a hook
    event from stdin as JSON, processes it, and outputs a JSON response to
    stdout that blocks the action if secrets are detected.

    To install the hook for your AI coding assistants, run `ggshield machine
    setup`.
    """
    ctx_obj = ContextObj.get(ctx)

    # Read input from stdin
    stdin_content = sys.stdin.read(MAX_READ_SIZE).strip()

    try:
        config = ctx_obj.config
        with _keychain_dialogs():
            ctx_obj.client = create_client_from_config(config)
        scanner = SecretScanner(
            client=ctx_obj.client,
            cache=ctx_obj.cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.AI_HOOK,
                command_path=ctx.command_path,
                extra_headers=build_agent_headers(stdin_content),
                endpoint_registration=config.user_config.endpoint_registration,
            ),
            # The hook always scans and never creates incidents: source_uuid
            # would route it to scan_and_create_incidents, which cannot request
            # `all_secrets`. Other commands keep it.
            secret_config=replace(config.user_config.secret, source_uuid=None),
        )
        return AIHookScanner(scanner, ctx_obj.exclusion_regexes).scan(stdin_content)
    except UnrecognizedAgentError as e:
        return emit_cannot_scan_response(stdin_content, e, _fail(ctx_obj))
    except ValueError as e:
        ui.display_error(str(e.args[0]))
        return 1
    except Exception as e:
        # Auth, network or any unexpected failure: the event was not scanned.
        return emit_cannot_scan_response(stdin_content, e, _fail(ctx_obj))
