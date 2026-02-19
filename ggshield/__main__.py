#!/usr/bin/python3
import logging
import multiprocessing
import os
import sys
from io import TextIOWrapper
from pathlib import Path
from typing import Any, List, Optional

import click

from ggshield import __version__
from ggshield.cmd.auth import auth_group
from ggshield.cmd.config import config_group
from ggshield.cmd.hmsl import hmsl_group
from ggshield.cmd.honeytoken import honeytoken_group
from ggshield.cmd.install import install_cmd
from ggshield.cmd.plugin import plugin_group
from ggshield.cmd.quota import quota_cmd
from ggshield.cmd.secret import secret_group
from ggshield.cmd.secret.scan import scan_group
from ggshield.cmd.status import status_cmd
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.debug import setup_debug_mode
from ggshield.core import check_updates, ui
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.env_utils import load_dot_env
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.loader import PluginLoader
from ggshield.core.plugin.registry import PluginRegistry
from ggshield.core.ui import ensure_level, log_utils
from ggshield.core.ui.rich import RichGGShieldUI
from ggshield.utils.click import RealPath
from ggshield.utils.os import getenv_bool


logger = logging.getLogger(__name__)


@scan_group.result_callback()
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


# Plugin registry, lazily initialized when _load_plugins() is called.
_plugin_registry: Optional[PluginRegistry] = None

# Warnings collected during plugin loading, before logging is configured.
_deferred_warnings: List[str] = []


def _load_plugins() -> PluginRegistry:
    """Load plugins at module level so commands are available."""
    global _plugin_registry
    if _plugin_registry is None:
        # Suppress signature/loader loggers during startup to avoid noisy output
        # before logging is configured
        sig_logger = logging.getLogger("ggshield.core.plugin.signature")
        loader_logger = logging.getLogger("ggshield.core.plugin.loader")
        orig_sig_level = sig_logger.level
        orig_loader_level = loader_logger.level
        sig_logger.setLevel(logging.CRITICAL)
        loader_logger.setLevel(logging.CRITICAL)

        try:
            enterprise_config = EnterpriseConfig.load()
            plugin_loader = PluginLoader(enterprise_config)
            _plugin_registry = plugin_loader.load_enabled_plugins()
        except Exception as e:
            _deferred_warnings.append(f"Failed to load plugins: {e}")
            _plugin_registry = PluginRegistry()
        finally:
            sig_logger.setLevel(orig_sig_level)
            loader_logger.setLevel(orig_loader_level)

        # Make registry available to hooks module
        from ggshield.core.plugin.hooks import set_plugin_registry

        set_plugin_registry(_plugin_registry)
    return _plugin_registry


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    commands={
        "auth": auth_group,
        "config": config_group,
        "plugin": plugin_group,
        "secret": secret_group,
        "install": install_cmd,
        "quota": quota_cmd,
        "api-status": status_cmd,
        "honeytoken": honeytoken_group,
        "hmsl": hmsl_group,
    },
)
@click.option(
    "-c",
    "--config-path",
    type=RealPath(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
    is_eager=True,
    help="Set a custom config file. Ignores local and global config files.",
)
@click.option(
    "--instance",
    required=False,
    type=str,
    help="URL of the GitGuardian instance to use.",
    metavar="URL",
)
@add_common_options()
@click.version_option(version=__version__)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    allow_self_signed: Optional[bool],
    insecure: Optional[bool],
    config_path: Optional[Path],
    instance: Optional[str],
    **kwargs: Any,
) -> None:
    # Create ContextObj, load config
    ctx.obj = ctx_obj = ContextObj()
    ctx_obj.cache = Cache()
    ctx_obj.config = Config(config_path)
    user_config = ctx_obj.config.user_config

    # If the config wants a higher UI level, set it now
    if user_config.debug and ui.get_level() < ui.Level.DEBUG:
        setup_debug_mode()
    elif user_config.verbose and ui.get_level() < ui.Level.VERBOSE:
        ensure_level(ui.Level.VERBOSE)

    # Update SSL verification settings in the config
    # TODO: this should be reworked: if a command which writes the config is called with
    # --insecure, the config will contain `insecure: true`.
    if insecure or allow_self_signed:
        user_config.insecure = True

    ctx_obj.config._dotenv_vars = load_dot_env()

    # Apply instance from command line
    if instance:
        ctx_obj.config.cmdline_instance_name = instance

    # Use pre-loaded plugin registry
    ctx_obj.plugin_registry = _load_plugins()

    # Flush deferred plugin warnings now that logging is configured
    for msg in _deferred_warnings:
        logger.warning(msg)
    _deferred_warnings.clear()

    _set_color(ctx)


# Register plugin commands with the CLI group.
# Called from main() to avoid import-time side effects.
def _register_plugin_commands() -> None:
    """Register plugin commands with the CLI."""
    try:
        registry = _load_plugins()
        existing_commands = set(cli.commands)
        for cmd in registry.get_commands():
            cmd_name = cmd.name
            if not cmd_name:
                _deferred_warnings.append("Skipping unnamed plugin command")
                continue

            if cmd_name in existing_commands:
                _deferred_warnings.append(
                    "Skipping plugin command "
                    f"'{cmd_name}' because it conflicts with an existing command"
                )
                continue

            cli.add_command(cmd)
            existing_commands.add(cmd_name)
    except Exception as e:
        _deferred_warnings.append(f"Failed to register plugin commands: {e}")


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
        ui.display_warning(message)


def _check_for_updates(check_for_updates: bool) -> None:
    # Check for PYTEST_CURRENT_TEST to ensure update check does not happen when running
    # tests: we don't want it to happen because on the CI the unit test-suite is run
    # with --disable-socket, which causes failure on any network access.
    if check_for_updates and "PYTEST_CURRENT_TEST" not in os.environ:
        latest_version = check_updates.check_for_updates()
        if latest_version:
            ui.display_warning(
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


def force_utf8_output():
    """
    Force stdout and stderr to always be UTF-8. This is not the case on Windows
    when stdout or stderr is not the console. Doing this fixes integration with
    Visual Studio (see #170).
    """
    for out in sys.stdout, sys.stderr:
        # pyright is not sure sys.stdout and stderr are TextIOWrapper, so it complains when
        # calling `reconfigure()` on them, unless this check is there.
        assert isinstance(out, TextIOWrapper)
        out.reconfigure(encoding="utf-8")


def setup_truststore():
    """Use the system certificates instead of the ones bundled by certifi"""
    if sys.version_info < (3, 10):
        # truststore requires Python 3.10
        return

    import truststore

    truststore.inject_into_ssl()


def main(args: Optional[List[str]] = None) -> Any:
    """
    Wrapper around cli.main() to handle the GITGUARDIAN_CRASH_LOG variable.

    `args` is only used by unit-tests.
    """
    _register_plugin_commands()

    # Required by pyinstaller when forking.
    # See https://pyinstaller.org/en/latest/common-issues-and-pitfalls.html#multi-processing
    multiprocessing.freeze_support()

    log_utils.disable_logs()

    if not os.getenv("GG_PLAINTEXT_OUTPUT", False) and sys.stderr.isatty():
        ui.set_ui(RichGGShieldUI())

    force_utf8_output()
    setup_truststore()

    show_crash_log = getenv_bool("GITGUARDIAN_CRASH_LOG")
    return cli.main(args, prog_name="ggshield", standalone_mode=not show_crash_log)


if __name__ == "__main__":
    sys.exit(main())
