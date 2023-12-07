import os
from typing import Iterator, Tuple, Optional

import click
import hmsl_check

from ggshield.core.errors import UnexpectedError
from ggshield.verticals.hmsl.collection import SecretWithKey, collect_list
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client import VaultAPIClient
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.cli import get_vault_cli_token
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import VaultCliTokenFetchingError, \
    VaultForbiddenItemError


@hmsl_check.hookimpl
def cmd_options():
    return [
        click.option(
            "--use-cli-token",
            "use_cli_token",
            is_flag=True,
            show_default=True,
            default=False,
            help="Instead of getting the token from the environment variable, "
                 "get it from the CLI tool.",
        ),
        click.option(
            "--url",
            "url",
            required=False,
            type=str,
            help="The URL of the secret manager server.",
        ),
        click.option(
            "--recursive",
            "-r",
            "recursive",
            is_flag=True,
            show_default=True,
            default=False,
            help="If the secret manager path is a directory and not a file, explore recursively.",
        ),
        click.argument(
            "vault_path",
            type=str,
        ),
    ]

def _get_vault_token(self, use_cli_token):
    if use_cli_token:
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

def _split_vault_mount_and_path(self, initial_path: str) -> Tuple[str, str]:
    """
    From a given initial path like secret/my_app/prod/env, split it in two:
    first the mount name, then the path.
    """
    split_path = initial_path.lstrip("/").split("/")
    return (split_path[0], "/".join(split_path[1:]).strip("/"))


@hmsl_check.hookimpl
def collect_secrets(
    ctx: click.Context,
    path: str,
    args: str,
    use_cli_token: bool,
    url: Optional[str],
    recursive: bool,
    vault_path: str, **_
) -> Iterator[SecretWithKey]:
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
            raise Exception(
                "you need to specify the URL of your Vault, "
                "either through --url or in the VAULT_URL environment variable"
            )
    vault_token = _get_vault_token(use_cli_token)
    vault_client = VaultAPIClient(url, vault_token)

    # Get mount object and check it exists and we have access to it
    mount_name, secret_path = _split_vault_mount_and_path(vault_path)
    all_kv_mounts = list(vault_client.get_kv_mounts())
    mount = next(
        (item for item in all_kv_mounts if item.name == mount_name), None
    )
    if mount is None:
        raise UnexpectedError(
            f"mount {mount_name} not found. Make sure it exists and "
            "that your token has access to it."
        )
    try:
        result = vault_client.get_secrets(mount, secret_path, recursive)
    # catch this error here if the path provided is a file that we don't have access to
    except VaultForbiddenItemError:
        raise UnexpectedError(
            f"access to the given path '{vault_path}' was forbidden. "
            "Are you sure the permissions of the token are correct?"
        )
    return collect_list(result.secrets)
