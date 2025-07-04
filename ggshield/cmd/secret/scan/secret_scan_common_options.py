import uuid
from typing import Callable, List, Optional

import click

from ggshield.cmd.utils.common_options import (
    AnyFunction,
    add_common_options,
    create_config_callback,
    create_ctx_callback,
    exit_zero_option,
    get_config_from_context,
    instance_option,
    json_option,
    text_json_sarif_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.output_format import OutputFormat
from ggshield.core import ui
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.filter import init_exclusion_regexes
from ggshield.utils.click import RealPath
from ggshield.verticals.secret.output import (
    SecretJSONOutputHandler,
    SecretOutputHandler,
    SecretSARIFOutputHandler,
    SecretTextOutputHandler,
)


IGNORED_DEFAULT_WILDCARDS = [
    "**/.git/*/**/*",  # only keep files in .git/ but not in subdirectories
    "**/.pytest_cache/**/*",
    "**/.mypy_cache/**/*",
    "**/.venv/**/*",
    "**/.eggs/**/*",
    "**/.eggs-info/**/*",
    "**/vendor/**/*",
    "**/vendors/**/*",
    "**/node_modules/**/*",
    "top-1000.txt*",
    "**/*.storyboard*",
    "**/*.xib",
    "**/*.mdx*",
    "**/*.sops",
]


def _get_secret_config(ctx: click.Context) -> SecretConfig:
    return get_config_from_context(ctx).secret


_output_option = click.option(
    "--output",
    "-o",
    type=RealPath(exists=False, resolve_path=True),
    default=None,
    help="Redirect ggshield output to PATH.",
    callback=create_ctx_callback("output"),
)


_show_secrets_option = click.option(
    "--show-secrets",
    is_flag=True,
    default=None,
    help="Show secrets in plaintext instead of hiding them.",
    callback=create_config_callback("secret", "show_secrets"),
)


def _exclude_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[List[str]]
) -> Optional[List[str]]:
    ignored_paths = _get_secret_config(ctx).ignored_paths
    if value is not None:
        ignored_paths.update(value)

    ignored_paths.update(IGNORED_DEFAULT_WILDCARDS)
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.exclusion_regexes = init_exclusion_regexes(ignored_paths)
    return value


_exclude_option = click.option(
    "--exclude",
    default=None,
    help="""
    Do not scan paths that match the specified glob-like patterns.
    """,
    multiple=True,
    callback=_exclude_callback,
    metavar="PATTERNS",
)


_ignore_known_secrets_option = click.option(
    "--ignore-known-secrets",
    is_flag=True,
    # The default value **must** be set to None.
    # Each command or subcommand calls create_config_callback to gather option values.
    # If the option is placed early in the command line, the value may be overridden
    # later on with False if no default is defined.
    default=None,
    help="Ignore secrets already known by GitGuardian dashboard.",
    callback=create_config_callback("secret", "ignore_known_secrets"),
)


def _banlist_detectors_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[List[str]]
) -> Optional[List[str]]:
    if value is not None:
        config = _get_secret_config(ctx)
        config.ignored_detectors.update(value)

    return value


_banlist_detectors_option = click.option(
    "--banlist-detector",
    "-b",
    default=None,
    help="Exclude results from a detector.",
    multiple=True,
    callback=_banlist_detectors_callback,
    metavar="DETECTOR",
)


_with_incident_details_option = click.option(
    "--with-incident-details",
    is_flag=True,
    # The default value **must** be set to None.
    # Each command or subcommand calls create_config_callback to gather option values.
    # If the option is placed early in the command line, the value may be overridden
    # later on with False if no default is defined.
    default=None,
    help="""Display full details about the dashboard incident if one is found (JSON and SARIF formats only). Requires the 'incidents:read' scope.""",  # noqa
    callback=create_config_callback("secret", "with_incident_details"),
)


_all_secrets = click.option(
    "--all-secrets",
    is_flag=True,
    help=("Do not ignore any secret. Possible ignore-reason is shown as well."),
    callback=create_config_callback("secret", "all_secrets"),
    default=None,
)


def _source_uuid_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[str]:
    if value is not None:
        try:
            uuid.UUID(value)
        except ValueError:
            raise click.BadParameter("source-uuid must be a valid UUID")
    return create_config_callback("secret", "source_uuid")(ctx, param, value)


_source_uuid_option = click.option(
    "--source-uuid",
    help="Identifier of the custom source in GitGuardian. If used, incidents will be created and visible on the "
    "dashboard. Requires the 'scan:create-incidents' scope.",
    callback=_source_uuid_callback,
    default=None,
)


def add_secret_scan_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        add_common_options()(cmd)
        json_option(cmd)
        text_json_sarif_format_option(cmd)
        _output_option(cmd)
        _show_secrets_option(cmd)
        exit_zero_option(cmd)
        _exclude_option(cmd)
        _ignore_known_secrets_option(cmd)
        _banlist_detectors_option(cmd)
        _with_incident_details_option(cmd)
        instance_option(cmd)
        _all_secrets(cmd)
        _source_uuid_option(cmd)
        return cmd

    return decorator


OUTPUT_HANDLER_CLASSES = {
    OutputFormat.TEXT: SecretTextOutputHandler,
    OutputFormat.JSON: SecretJSONOutputHandler,
    OutputFormat.SARIF: SecretSARIFOutputHandler,
}


def create_output_handler(ctx: click.Context) -> SecretOutputHandler:
    """Read objects defined in ctx.obj and create the appropriate OutputHandler
    instance"""
    ctx_obj = ContextObj.get(ctx)
    output_handler_cls = OUTPUT_HANDLER_CLASSES[ctx_obj.output_format]
    config = ctx_obj.config
    return output_handler_cls(
        verbose=ui.is_verbose(),
        client=ctx_obj.client,
        output=ctx_obj.output,
        secret_config=config.user_config.secret,
    )
