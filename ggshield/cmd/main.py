#!/usr/bin/python3
import logging
import os
import sys
from typing import Any, List, Optional

import click
import pygitguardian

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


LOG_FORMAT = (
    "%(asctime)s %(levelname)s %(thread)d %(name)s:%(funcName)s:%(lineno)d %(message)s"
)

logger = logging.getLogger(__name__)


@scan_group.result_callback()
@deprecated_scan_group.result_callback()
@iac_group.result_callback()
@click.pass_context
def exit_code(ctx: click.Context, exit_code: int, **kwargs: Any) -> None:
    """
    exit_code guarantees that the return value of a scan is 0
    when exit_zero is enabled
    """
    show_config_deprecation_message(ctx)
    if ctx.obj["config"].exit_zero:
        logger.debug("scan exit_code forced to 0")
        sys.exit(0)

    logger.debug("scan exit_code=%d", exit_code)
    sys.exit(exit_code)


def setup_debug_logs(debug: bool) -> None:
    """Configure Python logger. Disable messages up to logging.ERROR level by default.

    The reason we disable error messages is that we call logging.error() in addition to
    showing user-friendly error messages, but we don't want the error logs to show up
    with the user-friendly error messages, unless --debug has been set.
    """
    level = logging.DEBUG if debug else logging.CRITICAL

    if sys.version_info[:2] < (3, 8):
        # Simulate logging.basicConfig() `force` argument, introduced in Python 3.8
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()
        logging.basicConfig(filename=None, level=level, format=LOG_FORMAT)
    else:
        logging.basicConfig(filename=None, level=level, format=LOG_FORMAT, force=True)

    if debug:
        # Silence charset_normalizer, its debug output does not bring much
        logging.getLogger("charset_normalizer").setLevel(logging.WARNING)


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
@click.option("--debug", is_flag=True, default=None, help="Show debug information.")
@click.version_option()
@click.pass_context
def cli(
    ctx: click.Context,
    config_path: Optional[str],
    verbose: bool,
    allow_self_signed: bool,
    debug: Optional[bool],
) -> None:
    load_dot_env()
    ctx.ensure_object(dict)

    # If --debug is set, setup logs *now*, otherwise log commands for the
    # creation of the Config instance will be ignored
    setup_debug_logs(debug is True)

    config = Config(config_path)

    if debug is not None:
        config.debug = debug
    elif config.debug:
        # if --debug is not set, but `debug` is set in the configuration file,
        # we still have to setup logs
        setup_debug_logs(True)

    ctx.obj["config"] = config
    ctx.obj["cache"] = Cache()

    if verbose is not None:
        config.verbose = verbose

    if allow_self_signed is not None:
        config.allow_self_signed = allow_self_signed

    logger.debug("args=%s", sys.argv)
    logger.debug("py-gitguardian=%s", pygitguardian.__version__)


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
