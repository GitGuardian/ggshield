import os
from typing import Any, Optional

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault import (
    VaultCliTokenFetchingError,
    get_vault_cli_token,
)


def _get_vault_token(use_vault_cli_token: bool) -> str:
    """
    Get the Vault token to use.
    """
    if use_vault_cli_token:
        try:
            return get_vault_cli_token()
        except VaultCliTokenFetchingError as exc:
            raise click.UsageError(
                f"could not get the token from Vault CLI: {str(exc)}"
            ) from exc

    env_token = os.getenv("VAULT_TOKEN")
    if env_token is None:
        raise click.UsageError(
            "you need to specify the Vault token to use, either through the VAULT_TOKEN"
            " environment variable or by using --use-cli-token to use the token "
            "from the Vault CLI."
        )

    return env_token


@click.command(hidden=True)
@click.option(
    "--use-cli-token",
    "use_cli_token",
    is_flag=True,
    show_default=True,
    default=False,
    help="Instead of getting the token from the environment variable, "
    "get it from the CLI tool.",
)
@click.option(
    "--url",
    "url",
    required=False,
    type=str,
    help="The URL of the secret manager server.",
)
@click.option(
    "--recursive",
    "-r",
    "recursive",
    is_flag=True,
    show_default=True,
    default=False,
    help="If the secret manager path is a directory and not a file, explore recursively.",
)
@click.argument(
    "vault_path",
    type=str,
)
@add_common_options()
@click.pass_context
def check_hashicorp_vault_cmd(
    ctx: click.Context,
    use_cli_token: bool,
    url: Optional[str],
    recursive: bool,
    vault_path: str,
    **kwargs: Any,
) -> int:
    """
    Check secrets of an Hashicorp Vault instance.
    Only compatible with the kv secret engine for now.

    Will use the VAULT_URL environment variable to get the Vault instance URL or
    the --url option if no environment variable is set.

    Will use the VAULT_TOKEN environment variable to authenticate, except
    if the --use-cli-token option is set.
    """

    # Get the Vault URL
    if url is None:
        url = os.getenv("VAULT_URL")
        if url is None:
            raise click.UsageError(
                "you need to specify the URL of your Vault, "
                "either through --url or in the VAULT_URL environment variable"
            )

    vault_token = _get_vault_token(use_cli_token)  # noqa: F841

    raise click.UsageError("command not yet implemented.")
