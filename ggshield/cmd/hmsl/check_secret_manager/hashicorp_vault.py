import os
from typing import Any, Optional, Tuple

import click

from ggshield.cmd.hmsl.hmsl_common_options import (
    full_hashes_option,
    naming_strategy_option,
)
from ggshield.cmd.hmsl.hmsl_utils import check_secrets
from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.core import ui
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import pluralize
from ggshield.verticals.hmsl.collection import NamingStrategy, collect_list, prepare
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client import (
    VaultAPIClient,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.cli import (
    get_vault_cli_token,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultCliTokenFetchingError,
    VaultForbiddenItemError,
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


def _split_vault_mount_and_path(initial_path: str) -> Tuple[str, str]:
    """
    From a given initial path like secret/my_app/prod/env, split it in two:
    first the mount name, then the path.
    """
    split_path = initial_path.lstrip("/").split("/")
    return (split_path[0], "/".join(split_path[1:]).strip("/"))


@click.command()
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
@text_json_format_option
@json_option
@full_hashes_option
@naming_strategy_option
@click.pass_context
def check_hashicorp_vault_cmd(
    ctx: click.Context,
    use_cli_token: bool,
    url: Optional[str],
    recursive: bool,
    vault_path: str,
    full_hashes: bool,
    naming_strategy: NamingStrategy,
    **kwargs: Any,
) -> int:
    """
    Check secrets of an Hashicorp Vault instance.
    Only compatible with the kv secret engines (v1 or v2) for now.

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
    vault_client = VaultAPIClient(url, vault_token)

    # Get mount object and check it exists and we have access to it
    mount_name, secret_path = _split_vault_mount_and_path(vault_path)
    all_kv_mounts = list(vault_client.get_kv_mounts())
    mount = next((item for item in all_kv_mounts if item.name == mount_name), None)
    if mount is None:
        raise UnexpectedError(
            f"mount {mount_name} not found. Make sure it exists and "
            "that your token has access to it."
        )

    ui.display_info("Fetching secrets from Vault...")
    try:
        result = vault_client.get_secrets(mount, secret_path, recursive)
    # catch this error here if the path provided is a file that we don't have access to
    except VaultForbiddenItemError:
        raise UnexpectedError(
            f"access to the given path '{vault_path}' was forbidden. "
            "Are you sure the permissions of the token are correct?"
        )

    if len(result.not_fetched_paths) > 0:
        ui.display_error(
            f"Could not fetch {len(result.not_fetched_paths)} paths. "
            "Make sure your token has access to all the secrets in your vault."
        )
        if ui.is_verbose():
            ui.display_error("> The following paths could not be fetched:")
            for path in result.not_fetched_paths:
                ui.display_error(f"- {path}")
    ui.display_info(
        f"Got {len(result.secrets)} {pluralize('secret', len(result.secrets))}."
    )

    collected_secrets = collect_list(result.secrets)
    # full_hashes is True because we need the hashes to decrypt the secrets.
    # They will correctly be truncated by our client later (same as normal check cmd)
    prepared_secrets = prepare(collected_secrets, naming_strategy, full_hashes=True)

    check_secrets(
        ctx=ctx,
        prepared_secrets=prepared_secrets,
        full_hashes=full_hashes,
    )

    return 0
