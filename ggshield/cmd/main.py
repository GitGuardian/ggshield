#!/usr/bin/python3
import logging
import os
import sys
from typing import Any, List, Optional

import click

from ggshield.cmd.auth import auth_group
from ggshield.cmd.common_options import add_common_options
from ggshield.cmd.config import config_group
from ggshield.cmd.debug_logs import setup_debug_logs
from ggshield.cmd.iac import iac_group
from ggshield.cmd.install import install_cmd
from ggshield.cmd.quota import quota_cmd
from ggshield.cmd.scan import deprecated_scan_group
from ggshield.cmd.secret import secret_group
from ggshield.cmd.secret.ignore import deprecated_ignore_cmd
from ggshield.cmd.secret.scan import scan_group
from ggshield.cmd.status import status_cmd
from ggshield.core import check_updates
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.errors import ExitCode
from ggshield.core.text_utils import display_warning
from ggshield.core.utils import load_dot_env


logger = logging.getLogger(__name__)


@scan_group.result_callback()
@deprecated_scan_group.result_callback()
@iac_group.result_callback()
@click.pass_context
def exit_code(ctx: click.Context, exit_code: int, **kwargs: Any) -> int:
    """
    exit_code guarantees that the return value of a scan is 0
    when exit_zero is enabled
    """
    if exit_code == ExitCode.SCAN_FOUND_PROBLEMS and ctx.obj["config"].exit_zero:
        logger.debug("scan exit_code forced to 0")
        sys.exit(ExitCode.SUCCESS)

    logger.debug("scan exit_code=%d", exit_code)
    return exit_code


def config_path_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[str]:
    # The --config option is marked as "is_eager" to ensure it's called before all the
    # others. This makes it the right place to create the configuration object.
    if not ctx.obj:
        ctx.obj = {"cache": Cache()}

    ctx.obj["config"] = Config(value)
    return value


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
    is_eager=True,
    help="Set a custom config file. Ignores local and global config files.",
    callback=config_path_callback,
)
@add_common_options()
@click.version_option()
@click.pass_context
def cli(
    ctx: click.Context,
    debug: Optional[bool],
    **kwargs: Any,
) -> None:
    load_dot_env()

    config = ctx.obj["config"]
    if debug:
        # --debug was set. Update the config to reflect this. Unlike other options, this
        # can't be done in the debug_callback() because --debug is eager, so its
        # callback can be called *before* the configuration has been loaded.
        config.debug = True
    elif config.debug:
        # if --debug is not set but `debug` is set in the configuration file, then
        # we must setup logs now.
        setup_debug_logs(True)


def _display_deprecation_message(cfg: Config) -> None:
    for message in cfg.user_config.deprecation_messages:
        display_warning(message)


def _check_for_updates(check_for_updates: bool) -> None:
    # Check for PYTEST_CURRENT_TEST to ensure update check does not happen when running
    # tests: we don't want it to happen because on the CI the unit test-suite is run
    # with --disable-socket, which causes failure on any network access.
    if check_for_updates and "PYTEST_CURRENT_TEST" not in os.environ:
        latest_version = check_updates.check_for_updates()
        if latest_version:
            display_warning(
                f"A new version of ggshield (v{latest_version}) has been released "
                f"(https://github.com/GitGuardian/ggshield)."
            )


@cli.result_callback()
@click.pass_context
def before_exit(ctx: click.Context, exit_code: int, *args: Any, **kwargs: Any) -> None:
    """
    This function is launched as a final callback once subcommands have run.
    It executes some final functions and then terminates.
    The argument exit_code is the result of the previously executed click command.
    """
    _display_deprecation_message(ctx.obj["config"])
    _check_for_updates(ctx.obj.get("check_for_updates", True))
    sys.exit(exit_code)


def main(args: Optional[List[str]] = None) -> Any:
    """
    Wrapper around cli.main() to handle the GITGUARDIAN_CRASH_LOG variable.

    `args` is only used by unit-tests.
    """
    show_crash_log = os.getenv("GITGUARDIAN_CRASH_LOG", "False").lower() == "true"
    return cli.main(args, prog_name="ggshield", standalone_mode=not show_crash_log)


if __name__ == "__main__":
    sys.exit(main())
