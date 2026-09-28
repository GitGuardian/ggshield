import inspect
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

import click
from typing_extensions import ParamSpec

from ggshield.cmd.utils.common_options import create_config_callback
from ggshield.core.errors import ServiceUnavailableError, handle_exception
from ggshield.utils.git_shell import GitExecutableNotFound


T = TypeVar("T")
P = ParamSpec("P")


def exception_wrapper(func: Callable[P, int]) -> Callable[P, int]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> int:
        try:
            return func(*args, **kwargs)
        except Exception as error:
            return handle_exception(error)

    return wrapper


fail_on_server_error_option = click.option(
    "--fail-on-server-error/--no-fail-on-server-error",
    "fail_on_server_error",
    is_flag=True,
    default=None,
    envvar="GITGUARDIAN_FAIL_ON_SERVER_ERROR",
    help=(
        "Whether git hook and CI scan commands should fail when the GitGuardian"
        " server is unreachable or returns a 5xx response. When disabled, the"
        " command exits with code 0 and a warning is displayed instead of"
        " blocking the git operation. Defaults to enabled. Can also be set with"
        " the `GITGUARDIAN_FAIL_ON_SERVER_ERROR` environment variable."
    ),
    callback=create_config_callback("secret", "fail_on_server_error"),
)


def non_blocking_on_server_error(func: Callable[P, int]) -> Callable[P, int]:
    """Decorator for git hook / CI commands that may opt in to not blocking
    when the GitGuardian server is unavailable.

    Bundles the ``--fail-on-server-error`` CLI option with a handler that
    catches ``ServiceUnavailableError``: when ``secret.fail_on_server_error``
    is False, the command exits with code 0 and a warning; otherwise the error
    is re-raised and handled like any other error.
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> int:
        try:
            return func(*args, **kwargs)
        except ServiceUnavailableError as exc:
            # Lazy import to avoid circular imports (same pattern as handle_exception).
            from ggshield.cmd.utils.context_obj import ContextObj
            from ggshield.core import ui

            ctx = click.get_current_context(silent=True)
            fail_on_server_error = True
            if ctx is not None and ctx.obj is not None:
                fail_on_server_error = ContextObj.get(
                    ctx
                ).config.user_config.secret.fail_on_server_error

            if fail_on_server_error:
                raise

            ui.display_error(str(exc))
            ui.display_error("Skipping ggshield checks.")
            return 0

    return fail_on_server_error_option(wrapper)


class GitUsage(Enum):
    """How a command relates to the git executable, declared with `uses_git`."""

    REQUIRED = "This command requires git to be installed and available in PATH."
    OPTIONAL = "Git is optional for this command."


def uses_git(
    usage: GitUsage, note: Optional[str] = None
) -> Callable[[click.Command], click.Command]:
    """Declare how a command uses git. Apply it above `@click.command()`.

    The help text gets the `usage` sentence, followed for `GitUsage.OPTIONAL` by
    `note`, which says which features need git. Git is looked up only when the
    command first calls it, so early exits such as `SKIP=ggshield` or a branch
    deletion push work without git. If git cannot be found, the command exits through
    `handle_exception`, with an error naming the command. `command.git_usage` records
    `usage` for the tests that keep the declarations complete.
    """
    if (usage is GitUsage.OPTIONAL) != bool(note):
        raise ValueError("`note` is required for, and only allowed on, optional git")

    def decorator(command: click.Command) -> click.Command:
        sentence = f"{usage.value} {note}" if note else usage.value
        command.help = f"{inspect.cleandoc(command.help or '')}\n\n{sentence}".strip()
        setattr(command, "git_usage", usage)
        callback = command.callback
        assert callback is not None

        @wraps(callback)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return callback(*args, **kwargs)
            except GitExecutableNotFound as exc:
                return handle_exception(exc)

        command.callback = wrapper
        return command

    return decorator
