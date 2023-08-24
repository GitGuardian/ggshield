from typing import Any

import click

from ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault import (
    check_hashicorp_vault_cmd,
)
from ggshield.cmd.utils.common_options import add_common_options


@click.group(
    commands={
        "hashicorp-vault": check_hashicorp_vault_cmd,
    },
)
@add_common_options()
def check_secret_manager_group(**kwargs: Any) -> None:
    """Check if secrets from a secret manager have leaked."""
    pass
