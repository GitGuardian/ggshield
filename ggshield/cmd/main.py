#!/usr/bin/python3
import os
import sys
from typing import Any, List, Optional

import click

from ggshield.cmd.auth import auth_group
from ggshield.cmd.config import config_group
from ggshield.cmd.iac import iac_group
from ggshield.cmd.install import install_cmd
from ggshield.cmd.quota import quota_cmd
from ggshield.cmd.scan import deprecated_scan_group
from ggshield.cmd.secret import secret_group
from ggshield.cmd.secret.ignore import deprecated_ignore_cmd
from ggshield.cmd.secret.scan import scan_group
from ggshield.cmd.status import status_cmd
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.text_utils import display_warning
from ggshield.core.utils import load_dot_env


@scan_group.result_callback()
@deprecated_scan_group.result_callback()
@click.pass_context
def exit_code(ctx: click.Context, exit_code: int, **kwargs: Any) -> None:
    """
    exit_code guarantees that the return value of a scan is 0
    when exit_zero is enabled
    """

    show_config_deprecation_message(ctx)
    if ctx.obj["config"].exit_zero:
        sys.exit(0)

    sys.exit(exit_code)


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    commands={
        "auth": auth_group,
        "config": config_group,
        "scan": deprecated_scan_group,
        "secret": secret_group,
        "install": install_cmd,
        "ignore": deprecated_ignore_cmd,
        "quota": quota_cmd,
        "api-status": status_cmd,
        "iac": iac_group,
    },
)
@click.option(
    "-c",
    "--config-path",
    type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
    help="Set a custom config file. Ignores local and global config files.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=None, help="Verbose display mode."
)
@click.option(
    "--allow-self-signed",
    is_flag=True,
    default=None,
    help="Ignore ssl verification.",
)
@click.version_option()
@click.pass_context
def cli(
    ctx: click.Context,
    config_path: Optional[str],
    verbose: bool,
    allow_self_signed: bool,
) -> None:
    load_dot_env()
    ctx.ensure_object(dict)

    ctx.obj["config"] = Config(config_path)
    ctx.obj["cache"] = Cache()

    if verbose is not None:
        ctx.obj["config"].verbose = verbose

    if allow_self_signed is not None:
        ctx.obj["config"].allow_self_signed = allow_self_signed


@cli.result_callback()
@click.pass_context
def show_config_deprecation_message(
    ctx: click.Context, *args: Any, **kwargs: Any
) -> None:
    cfg: Config = ctx.obj["config"]
    for message in cfg.user_config.deprecation_messages:
        display_warning(message)


def main(args: Optional[List[str]] = None) -> Any:
    """
    Wrapper around cli.main() to handle the GITGUARDIAN_CRASH_LOG variable.

    `args` is only used by unit-tests.
    """
    show_crash_log = os.getenv("GITGUARDIAN_CRASH_LOG", "False").lower() == "true"
    return cli.main(args, prog_name="ggshield", standalone_mode=not show_crash_log)


if __name__ == "__main__":
    sys.exit(main())
