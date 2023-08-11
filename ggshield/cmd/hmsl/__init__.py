from typing import Any

import click

from ggshield.cmd.common_options import add_common_options
from ggshield.cmd.hmsl.api_status import status_cmd
from ggshield.cmd.hmsl.check import check_cmd
from ggshield.cmd.hmsl.decrypt import decrypt_cmd
from ggshield.cmd.hmsl.fingerprint import fingerprint_cmd
from ggshield.cmd.hmsl.query import query_cmd
from ggshield.cmd.hmsl.quota import quota_cmd


@click.group(
    commands={
        "check": check_cmd,
        "decrypt": decrypt_cmd,
        "fingerprint": fingerprint_cmd,
        "query": query_cmd,
        "quota": quota_cmd,
        "api-status": status_cmd,
    },
)
@add_common_options()
def hmsl_group(**kwargs: Any) -> None:
    """Commands for HasMySecretLeaked."""
