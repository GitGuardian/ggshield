#!/usr/bin/python3
import logging
import os
import sys
from pathlib import Path
from typing import Any, List, Optional

import click

from ggshield.cmd.auth import auth_group
from ggshield.cmd.config import config_group
from ggshield.cmd.hmsl import hmsl_group
from ggshield.cmd.honeytoken import honeytoken_group
from ggshield.cmd.iac import iac_group
from ggshield.cmd.install import install_cmd
from ggshield.cmd.quota import quota_cmd
from ggshield.cmd.sca import sca_group
from ggshield.cmd.secret import secret_group
from ggshield.cmd.secret.scan import scan_group
from ggshield.cmd.status import status_cmd
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.debug_logs import disable_logs, setup_debug_logs
from ggshield.core import check_updates
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.env_utils import load_dot_env
from ggshield.core.errors import ExitCode
from ggshield.core.text_utils import display_warning
from ggshield.core.ui.plain_text.plain_text_ggshield_ui import PlainTextGGShieldUI
from ggshield.core.ui.rich.rich_ggshield_ui import RichGGShieldUI
from ggshield.utils.click import RealPath
from ggshield.utils.os import getenv_bool


logger = logging.getLogger(__name__)


@scan_group.result_callback()
@iac_group.result_callback()
@click.pass_context
def exit_code(ctx: click.Context, exit_code: int, **kwargs: Any) -> int:
    """
    exit_code guarantees that the return value of a scan is 0
    when exit_zero is enabled
    """
    ctx_obj = ContextObj.get(ctx)
    if (
        exit_code == ExitCode.SCAN_FOUND_PROBLEMS
        and ctx_obj.config.user_config.exit_zero
    ):
        logger.debug("scan exit_code forced to 0")
        sys.exit(ExitCode.SUCCESS)

    logger.debug("scan exit_code=%d", exit_code)
    return exit_code


def config_path_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[Path]
) -> Optional[Path]:
    # The --config option is marked as "is_eager" to ensure it's called before all the
    # others. This makes it the right place to create the configuration object.
    if not ctx.obj:
        ctx.obj = ContextObj()
        ctx.obj.cache = Cache()
        if sys.stderr.isatty():
            ctx.obj.ui = RichGGShieldUI()
        else:
            ctx.obj.ui = PlainTextGGShieldUI()

    ctx.obj.config = Config(value)
    return value


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    commands={
        "auth": auth_group,
        "config": config_group,
        "secret": secret_group,
        "install": install_cmd,
        "quota": quota_cmd,
        "api-status": status_cmd,
        "iac": iac_group,
        "honeytoken": honeytoken_group,
        "sca": sca_group,
        "hmsl": hmsl_group,
    },
)
@click.option(
    "-c",
    "--config-path",
    type=RealPath(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
    is_eager=True,
    help="Set a custom config file. Ignores local and global config files.",
    callback=config_path_callback,
)
@add_common_options()
@click.version_option()
@click.pass_context
def cli(
    ctx: click.Context,
    **kwargs: Any,
) -> None:
    load_dot_env()

    config = ContextObj.get(ctx).config

    _set_color(ctx)

    if config.user_config.debug:
        # if `debug` is set in the configuration file, then setup logs now.
        setup_debug_logs(filename=None)


def _set_color(ctx: click.Context):
    """
    Helper function to override the default click default output color setting.
        If NO_COLOR is set, we disable color output (see https://no-color.org/).
    If we are in a CI environment, certain variables are set, and we enable colors for
    the logs.
    """
    ci_env_vars = [
        "CI",  # Often set to indicate a generic CI environment
        "GITLAB_CI",
        "GITHUB_ACTIONS",
        "TRAVIS",
        "JENKINS_HOME",
        "JENKINS_URL",
        "CIRCLECI",
        "BITBUCKET_COMMIT",
        "DRONE",
        "BUILD_BUILDID",  # Azure Pipelines
    ]

    if os.getenv("NO_COLOR"):
        ctx.color = False
    elif any(os.getenv(env) for env in ci_env_vars):
        ctx.color = True


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
    ctx_obj = ContextObj.get(ctx)
    _display_deprecation_message(ctx_obj.config)
    _check_for_updates(ctx_obj.check_for_updates)
    sys.exit(exit_code)


def main(args: Optional[List[str]] = None) -> Any:
    """
    Wrapper around cli.main() to handle the GITGUARDIAN_CRASH_LOG variable.

    `args` is only used by unit-tests.
    """
    disable_logs()
    show_crash_log = getenv_bool("GITGUARDIAN_CRASH_LOG")
    return cli.main(args, prog_name="ggshield", standalone_mode=not show_crash_log)


if __name__ == "__main__":
    sys.exit(main())
